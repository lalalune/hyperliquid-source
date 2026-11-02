# RE-004: helper-1 operand shapes at the non-scaling call sites (node #94)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the call sites, prologue/setup anchors,
  context-field offsets, FDE bounds and window digests; inference for the
  operand-selection model (faithful translation of the prologue/setup
  instruction streams) and for the collapse consequences (via #161's
  proof); flag values are #160 oracle values (grid rows or runs of
  #160's own block-level simulation on the exact site shapes), cited
  not re-derived; unresolved items are listed under Results and
  limitations
- Scope included: the three non-scaling helper-1 sites' operand
  selection (caller-A call 1 at 0x279d1fc, caller-A call 2 at 0x279d2ab,
  caller-B at 0x279d51a), the shared min prologue, the call-2 gate and
  shift construction, and the 15-case shape model
- Scope excluded: the #160 helper inner loops and flag derivation
  itself (used only as an oracle), the #161 flag-consumption chains
  after the calls (reused only as the collapse rule), the scaling
  handlers (#157/#158/#159), the helper-2 sites, the context producers
  (what values P, Q, R, V, X, Y, W actually take in real executions),
  indirect callers, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/mul256_helper_operand_shapes94.py --out research/work-items/RE-004-mul256-helper-operand-shapes-94
python3 -m unittest discover -s tests -p 'test_mul256_helper_operand_shapes94.py'
(cd research/work-items/RE-004-mul256-helper-operand-shapes-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x279d0c0 --stop-address=0x279d200 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x279d3e0 --stop-address=0x279d51a artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the E8 census scan walks .text).
Outputs: `evidence.json`, `sites.tsv`, `cases.tsv` and `windows.txt`.

## Evidence

Coordinates are ELF virtual addresses. The #161 packet proved that a
helper-1 false positive collapses caller-A/B results to exactly 0 and
left open whether multi-limb helper inputs can actually reach the
helper-1 sites. This packet answers that question at the sites' own
input-selection layer: yes for sites A1 and B, and with a correction
for site A2.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the prologue/setup regions are
hashed in `evidence.json` and `windows.txt`. FDE bounds are
unwind-described ranges, not validated function boundaries. The claimed
windows sit inside the #161 FDE windows (same functions) but are
byte-disjoint from #161's anchored ranges (flag tests at 0x279d201 /
0x279d2b0 / 0x279d51f, sentinel presets, add/sub chains, counter/flag
tails), which all lie after the call sites or after the call-2 gate;
the generator asserts this disjointness. The behavior claimed here
(operand selection before the calls) is disjoint from #161's behavior
(flag consumption after the calls).

| Site | Call | Enclosing FDE | Out | `a` shape | `b` shape |
| --- | --- | --- | --- | --- | --- |
| A1 | 0x279d1fc | 0x279d0c0..0x279d3e0 | [rsp] | (V,0,0,0) | min(P+Q,R) or R |
| A2 | 0x279d2ab | 0x279d0c0..0x279d3e0 | [rsp] | (X,Y,0,0) | (W<<17,0,0,0) |
| B | 0x279d51a | 0x279d3e0..0x279d5e0 | [rsp+0x8] | (V,0,0,0) | min(P+Q,R) or R |

Context fields (all offsets relative to the context sub-object `rsi` at
each caller entry): V = [ctx+0x238]; flag178 = DWORD [ctx+0x178];
P = [ctx+0x180..0x198]; Q = [ctx+0x90..0xa8]; R = [ctx+0x240..0x250];
X = [ctx+0x10]; Y = [ctx+0x18]; W = [ctx+0x210]; gate = bit 0 of [ctx].

**Census (observation, re-derived by the tool from an E8 rel32 scan of
`.text`).** Exactly three helper-1 calls live inside the caller-A/B
FDEs: 0x279d1fc, 0x279d2ab, 0x279d51a. Caller-B has exactly one
helper-1 call; caller-A has two.

**Sites A1 and B: the shared min prologue (observation, byte-anchored
at both sites).** Each caller loads V = [ctx+0x238] into [rsp+0x78]
and zeroes [rsp+0x80..0x98] at entry, so the `a` operand slot at
[rsp+0x78] always reads (V,0,0,0): `a` is forced single-limb by
construction, whatever V is. It then tests DWORD [ctx+0x178] against
1. On the slow path (flag != 1) it copies R = [ctx+0x240..0x250]
directly to the `b` slot at [rsp+0x50]. On the fast path (flag == 1)
it computes S = P + Q as a 4-limb add (add/adc chain, mod 2^256),
compares S against R limb by limb from the top, and selects via
`cmovb` after the first differing limb: S when that limb is below
R's, R otherwise -- that is, min(S, R) -- into [rsp+0x50]. On equal
limbs it selects R (equal to S anyway). The call setup is then
`rdi` = out, `rsi` = [rsp+0x78] (`a`), `rdx` = [rsp+0x50] (`b`).
No step in either path reduces limb counts: a low-zero multi-limb
`b` passes through unchanged.

**Site A2: gate, two-limb `a`, shifted single-limb `b` (observation,
byte-anchored).** After call 1, caller-A tests bit 0 of [ctx]; when
clear it takes a panic path (no second product). When set it builds
`a` = (X, Y, 0, 0) at [rsp+0x50] from [ctx+0x10]/[ctx+0x18] (Y is
zeroed when [ctx+0x18] is zero) and `b` = (W<<17, 0, 0, 0) at
[rsp+0x30] from W = [ctx+0x210]: it requires W < 2^47 via `shr
rcx,0x2f` + `jne` to a panic path, then `shl rax,0x11`. The call
setup is `rdi` = out, `rsi` = [rsp+0x50] (`a`), `rdx` = [rsp+0x30]
(`b`). So call 2's `b` is always single-limb, and its `a` has at
most two limbs.

**Flag oracle (observation, #160's artifact).** #160's loop_cases.tsv
row `b_low_zero` (a = (5,0,0,0), b = (0,7,0,0), fitting product
(0,35,0,0)) has helper-1 flag 1; its `single_limb` row has flag 0.
Runs of #160's own block-level simulation on the exact site shapes
give: multi-limb `a` x single-limb `b` never flags (2/3/4-limb `a`
tested, flag 0 in every case -- the flag follows `b`'s shape, not
`a`'s); (X,0,0,0)-or-(X,Y,0,0) x (0,0,0,0) with X != 0 flags 1;
(0,0,0,0) x (0,0,0,0) flags 0; (0,Y,0,0) x (0,0,0,0) falls in #160's
out-of-scope region (a_skip + b_skip > 4) and is not claimed.

## Inferences

- **The #161 collapse is live at sites A1 and B, not merely latent.**
  Case C1 (slow path, V = 5, R = (0,7,0,0)) reproduces #161's A2 shape
  exactly: `a` = (5,0,0,0) is forced by the zeroed stack slots, `b` =
  R = (0,7,0,0) passes the prologue untouched, the product (0,35,0,0)
  fits, and helper-1 flags 1 -- so the caller result collapses to 0
  by #161's proof while the flag-free result would be (965,65,100,0).
  The fast-path cases C2/C3/C5 reach the same `b` through min(S, R),
  and site B mirrors A1 (C6/C7). Nothing in the prologue prevents
  this shape; only the context producers could, and they are out of
  scope here.
- **Correction to #161's A3 mapping.** #161's case A3 assigns call 2
  the `two_limb_fit` scenario (flag 1), whose #160 row has a two-limb
  `b` ((1,2,0,0) x (3,4,0,0)). Call 2's `b` is always single-limb, so
  that scenario cannot occur at call 2, and #160's simulation shows
  the reachable two-limb-`a` x single-limb-`b` shape does not flag
  (case C8, flag 0, no collapse). The #161 packet is not modified
  here; this packet records the corrected mapping for call 2.
- **Call 2's only flag path is W = 0 with X != 0** (case C10): `b` =
  0 short-circuits to flag 1 in #160's simulation even though the
  product is genuinely 0, so the sentinel still destroys the sum
  (collapse by #161's proof). X = Y = 0 with W = 0 gives flag 0
  (case C10c); X = 0, Y != 0 with W = 0 is out of scope (case C10b,
  no flag claim).
- **Call 2 can never truly overflow.** a2 < 2^128 and b2 < 2^64 (the
  panic guard enforces W < 2^47), so every call-2 product is below
  2^192 (case C13 hits exactly 192 bits at maximum inputs). At call
  2, flag = 1 therefore never means true overflow -- it means only
  the W = 0 path (X != 0).
- **The flag follows `b`, not `a`.** Across all three sites, the
  reachable false positives are exactly the shapes where `b` is
  multi-limb with a low zero limb (A1/B) or zero (A2, X != 0). A
  multi-limb `a` alone never flags at any site in this family.

## Results and limitations

- The operand-selection model is a faithful translation of the
  prologue/setup instruction streams, verified anchor by anchor
  against the disassembly; it is not an execution of the node binary,
  which this task forbids.
- Flag values are #160 oracle values, not independently derived here:
  grid rows for the A1/B shapes, runs of #160's simulation for the
  A2 shapes. If #160's simulation is wrong, the A2 flag claims
  inherit that error; the shape derivations (which operands reach
  each site) do not depend on the simulation.
- Out of scope, by precondition, not by oversight: the context
  producers (whether R = (0,7,0,0), W = 0, or any other witness
  value actually occurs in a real execution); the X = 0, Y != 0,
  W = 0 corner (out of #160's scope); the wider purpose of the
  caller-A/B host functions; later readers of the mutated object
  (#162's open question, still open); and node #115.
- Unresolved: whether the context producers ever emit the witness
  shapes (that decides whether the live collapse is exercised, as
  opposed to merely reachable through this layer).

## Next question

- Do the context producers (the writers of [ctx+0x240], [ctx+0x210],
  [ctx+0x180]/[ctx+0x90]) ever emit low-zero multi-limb R values or
  W = 0 in practice? That decides whether the reachable collapse at
  A1/B and the W = 0 collapse at A2 are exercised or only reachable.
