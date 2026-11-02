# RE-004: core-to-EVM scaling for non-negative evm_extra_wei_decimals in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made;
  the reference submodule was empty in this worktree
- Claim status: observation for the instructions, constants, call structure
  and evaluated behaviour; inference for the direction, the field meaning
  and the flipped flag; unresolved items are listed under
  Results and limitations
- Scope included: the positive entry, the square-and-multiply pow10 loop,
  the d == 0 shortcut, the final amount-times-pow10 checked multiply, the
  shared fallback address, the two checked-multiply helper contracts, and
  the census of both helpers' call sites
- Scope excluded: the negative-decimals divide mechanism (a separate packet),
  the remainder of the three 6 KB handlers, the helpers' inner schoolbook
  loops, the flow after the success flag flip, the other callers of the two
  helpers, the EVM-to-core scaler, the spot-wei-scale family, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/core_evm_positive_scale94.py --out research/work-items/RE-004-core-evm-positive-decimals-scale-94
python3 -m unittest discover -s tests -p 'test_core_evm_positive_scale94.py'
(cd research/work-items/RE-004-core-evm-positive-decimals-scale-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x2715756 --stop-address=0x27159fc artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4d0ab0c --stop-address=0x4d0ae18 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4d0c3dc --stop-address=0x4d0c6e8 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 5 s.
Outputs: `evidence.json`, `sites.tsv`, `loop_cases.tsv`, `final_cases.tsv`
and `windows.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. The positive entry is reached from the
sign test mapped in the negative-decimals packet: when the record byte at
+0xd1 is non-negative as i8, the byte is kept (zero-extended) as r15 and
control reaches the positive entry below. The negative packet's fragment,
scan, load and flag addresses are not repeated here.

**Boundaries.** Three handler copies carry the same positive path. The FDE
bounds come from the repository unwind index; the entry, loop, shortcut and
final windows are transcribed byte-for-byte in `windows.txt` and hashed in
`evidence.json`.

| Copy | FDE | Positive entry | Helper | Fallback | Amount slot | Flag slot | Result slot |
| --- | --- | --- | --- | --- | --- | --- | --- |
| copy-1 | 0x2715320..0x2716bc0 | 0x2715756 | 0x27a1150 | 0x271628d | [rsp+0x58] | [rsp+0x50] | [rsp+0x1f0] |
| copy-2 | 0x4d0a6d0..0x4d0bfa0 | 0x4d0ab0c | 0x4de5500 | 0x4d0b690 | [rsp+0x48] | [rsp+0xe8] | [rsp+0x210] |
| copy-3 | 0x4d0bfa0..0x4d0d870 | 0x4d0c3dc | 0x4de5500 | 0x4d0cf60 | [rsp+0x48] | [rsp+0xe8] | [rsp+0x210] |

All anchor byte strings (base init, movzx, pre-loop check, loop test, the
three helper calls with their rel32 targets, both overflow folds, the
shortcut constant load, the final overflow test, the fallback jumps and the
flag flip) are verified by the generator in every copy; only register
allocation and stack slots differ between copies.

**Entry.** The positive entry zeroes a 32-byte base slot and stores 10 in
its low limb (`mov [base],0xa`), zeroes a 32-byte accumulator slot and
stores 1 in its low limb, and zeroes a 32-byte exponent slot whose low limb
is the decimals byte. A pre-loop check ORs the exponent slot's limbs: if all
are zero (d == 0) it takes the shortcut below; otherwise it enters the loop.

**Shortcut (d == 0).** The shortcut loads one .rodata qword at 0x20a720
(verified value 1) into the low limb of the pow10 slot and zeroes the other
limbs, then joins the final multiply. So 10^0 = 1 without running the loop.

**Loop.** Square-and-multiply over 32-byte values, one bit of d per
iteration: if the current bit is set, acc = mul(acc, base); then unconditionally
base = mul(base, base); then d >>= 1. The loop condition ORs the four limbs
of the exponent slot, so it runs until the shifted byte reaches zero. The
accumulator overflow flag and the square overflow flag accumulate into bl
(copy-1 folds the helper's out+0x20 byte; copies 2/3 fold the helper's al
return). At loop exit, bl == 1 jumps to the fallback; otherwise the
accumulator is the pow10 slot.

**Fold subtlety (observed, modelled exactly).** A square overflow is folded
into bl only at a later bit-set iteration, so a square overflow on the final
iteration is dropped: for d in 64..77 the last iteration squares 10^64 to
10^128, which overflows, yet the loop still succeeds with the exact pow10,
because the accumulator never multiplied by the overflowed base. This cannot
change any verdict: for d <= 77 the accumulator is exact, and for d >= 78
the accumulator multiply itself overflows at or before the final set bit.
`loop_cases.tsv` lists all 256 byte values with the simulated verdict.

**Loop boundary.** The loop succeeds exactly for d in 0..77 and falls back
for d in 78..255: 10^77 < 2^256 < 10^78, and the accumulator multiply is
what overflows first for every d >= 78.

**Final multiply.** The amount (u64, copy-1 slot [rsp+0x58], copies 2/3 slot
[rsp+0x48]) is zero-extended into a 32-byte slot and multiplied by the pow10
slot through the same helper. Copy-1 tests the out+0x20 byte; copies 2/3
test al. Nonzero means fallback (the same fallback address as the loop
overflow). On success the 32-byte product is stored to the result slot and
the saved flag byte is flipped (`xor ...,0x1`); the flag's meaning is
unresolved (see below).

**Final boundary.** The final multiply overflows exactly when
amount * 10^d >= 2^256. `final_cases.tsv` grids amounts {0, 1, 2, 2^64 - 1,
threshold - 1, threshold} for d in {0, 1, 2, 18, 19, 77}, where threshold is
ceil(2^256 / 10^d). Through legitimate records (d in 0..18 per the admission
packet, amount a u64) the product is at most (2^64 - 1) * 10^18, far below
2^256, so the final multiply cannot overflow there; the check is defence
for out-of-range bytes, not a reachable failure.

**Helpers (call-site contract only).** The inner schoolbook loops are not
decoded. What the call sites establish:

| Helper | FDE | Signature at the call sites | Overflow signal |
| --- | --- | --- | --- |
| 0x27a1150 (copy-1) | 0x27a1150..0x27a1630 | (out, a, b); 32-byte values | byte at out+0x20 (`mov [rdi+0x20],al`) |
| 0x4de5500 (copies 2/3) | 0x4de5500..0x4de59d0 | (out, count=4, a, b); out pre-zeroed by the caller | al return (0 exact, 1 overflow; `mov al,0x1` sites, zeroed entry) |

**Census.** A plain-pattern scan of .text for E8 calls to either helper
finds exactly 14 sites: the 9 mapped here plus 5 other-caller sites, listed
in `evidence.json` with their enclosing FDEs (helper 0x27a1150: 0x279d1fc and
0x279d2ab in FDE 0x279d0c0, 0x279d51a in FDE 0x279d3e0; helper 0x4de5500:
0x4c90193 in FDE 0x4c900a0, 0x4c994ff in FDE 0x4c99440). Those five sites
are not mapped; they are recorded only to close the census.

**Related work.** The negative-decimals packet maps the same three handlers
for d < 0 (pow10 ladder, exact divide, same fallback addresses). This packet
is its positive half: same record byte (+0xd1), same handlers, same
fallback, opposite operation (checked multiply instead of exact divide).
The ladder shape is shared codegen, not a claim overlap. The spot-wei-scale
family is a different field and operation and is not touched.

## Inferences

- This is the core-to-EVM direction, the same direction as the negative
  packet: the same handlers, the same record byte, and the sign test that
  splits the two paths. The bytes do not name the direction.
- +0xd1 is `evm_extra_wei_decimals`, as pinned by the admission packet and
  the negative packet.
- The amount is a u64 zero-extended to 256 bits for the multiply; the
  product is a full 256-bit value, not a u64.
- The flipped flag byte plausibly marks the value as scaled, but its
  meaning is unresolved and is not claimed.

## Implementation and comparison

Rust implementation: not yet implemented. No binary comparison was measured.

## Results and limitations

Metrics are in `evidence.json`.

- Loop values: 256 of 256 byte values modelled, 78 exact (d 0..77),
  178 fallback (d 78..255).
- Copies: 3 of 3 share every anchor byte string up to register allocation
  and stack slots; both helper variants' contracts verified at all 9 mapped
  call sites.
- Final grid: 35 vectors (d in {0, 1, 2, 18, 19} x 6 amounts, d = 77 x 4
  amounts after the threshold collapses into the base grid, plus the
  loop-overflow row for d = 78), 0 mismatches against the closed form
  (product mod 2^256, overflow flag, outcome).
- Census: 14 of 14 helper call sites accounted for, 0 unaccounted.
- Tests: 19, including mutated base immediates, movzx, call rel32s, fold
  bytes, fallback jumps, shortcut constants and helper overflow bytes, each
  of which makes the generator fail, plus one non-anchor control that still
  generates identically.

Limits:

- The helpers' inner multiply loops are mapped only at the call-site
  contract level (inputs, output layout, overflow signal); the limb
  arithmetic inside is not claimed.
- The five other-caller call sites are not mapped; what those callers use
  the checked multiply for is unknown.
- The post-success flow (what consumes the 32-byte result and the flipped
  flag) is not mapped.
- The three handlers' callers are unresolved; the handlers are identified
  only by their FDEs and their shared fragments.
- The final grid is boundary and seeded values, not all 2^64 amounts. The
  boundary rows rest on the evaluated neighbours plus monotonicity of
  floor multiplication.
- Node #115 is not covered. No progress gate is requested.

Next question: what do the five other-caller sites use the two checked
multiplies for — do they share this scaling pattern, or a different
256-bit checked operation?
