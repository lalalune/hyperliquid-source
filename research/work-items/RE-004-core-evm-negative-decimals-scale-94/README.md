# RE-004: core-to-EVM scaling for negative evm_extra_wei_decimals in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made;
  the reference submodule was empty in this worktree
- Claim status: observation for the instructions, constants, call structure
  and evaluated behaviour; inference for the direction, the field meaning and
  the 20-byte field at +0xbd; unresolved items are listed under
  Results and limitations
- Scope included: the scaling fragment in three handler copies (record scan,
  sign test, pow10 ladder, divide, exactness decision, fallback coordinates),
  the census of +0xd1 byte loads, and the native-token default-10 branch
- Scope excluded: the positive-decimals multiply mechanism, the remainder of
  the three 6 KB handlers, the 0x27a1150 helper, the flow after the
  success-join, the EVM-to-core scaler (a separate packet), the spot-wei-scale
  family (a separate packet), the struct-copy site's purpose, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/core_evm_negative_scale94.py --out research/work-items/RE-004-core-evm-negative-decimals-scale-94
python3 -m unittest discover -s tests -p 'test_core_evm_negative_scale94.py'
(cd research/work-items/RE-004-core-evm-negative-decimals-scale-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x271563a --stop-address=0x2715741 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x271627d --stop-address=0x27163e8 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 10 s.
Outputs: `evidence.json`, `sites.tsv`, `ladder.tsv`, `cases.tsv`,
`divide_cases.tsv` and `fragment-bytes.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses.

**Boundaries.** Three handler copies carry the same fragment (263-byte
scan-to-divide window in each). The FDE bounds come from the repository
unwind index; the fragment windows are transcribed byte-for-byte in
`fragment-bytes.txt` and hashed in `evidence.json`.

| Copy | FDE | Scan | Decimals load | Divide entry | Success-join | Fallback |
| --- | --- | --- | --- | --- | --- | --- |
| copy-1 | 0x2715320..0x2716bc0 | 0x271563a | 0x271568d | 0x2715724 | 0x27163e8 | 0x271628d |
| copy-2 | 0x4d0a6d0..0x4d0bfa0 | 0x4d0a9f0 | 0x4d0aa43 | 0x4d0aada | 0x4d0b7e8 | 0x4d0b690 |
| copy-3 | 0x4d0bfa0..0x4d0d870 | 0x4d0c2c0 | 0x4d0c313 | 0x4d0c3aa | 0x4d0d0b8 | 0x4d0cf60 |

All anchor byte strings (scan imul, flag compare, decimals load, ladder
immediates, checked multiply, both divides, remainder test, fallback field
load, fallback tag, flag-error tag, native-10 setup) are identical across
the three copies except for register allocation and stack slots. The
generator verifies every anchor and fails on any mismatch.

**Record layout (observed in the fragment).** Records are indexed by
`imul $0xe8` (stride 232). The fragment requires flag byte +0xbc to equal
1; otherwise it takes the error path with tag 0x14a (330). It then copies a
20-byte field at +0xbd..0xd1 (16 bytes by movdqu plus a dword at +0xcd) and
loads the decimals byte at +0xd1 (movzbl). The amount divided is the u64 at
offset 8 of the input struct (copy-1 stack slot 0x58(%rsp), copies 2/3 slot
0x48(%rsp)).

**Branch.** `test %dl,%dl` on the decimals byte: sign bit clear (d >= 0)
jumps to the positive entry, where the byte is kept as r15 and the fragment
below does not run. Sign bit set (d < 0) falls through to the ladder. A
separate null-pointer branch saves the input and forces dl = 10 before
joining the positive entry; 10 is the native-token exponent (18 EVM decimals
over 8 core decimals, as in the EVM-to-core packet's fixed-exponent site).

**Ladder.** The negative path negates the byte (`neg %al`, so al = |d| for
d in -1..-127, and 128 for d = -128) and runs a square-and-multiply ladder
over bits 0..4 with immediates 10, 100, 10^4, 10^8, 10^16:

| Bit | Immediate | Cumulative pow10 (all lower bits set) | Early exit after this bit |
| --- | --- | --- | --- |
| 0 | 10 | 10^1 | al == 1 |
| 1 | 100 | 10^3 | (al & ~1) == 2 |
| 2 | 10^4 | 10^7 | (al & ~3) == 4 |
| 3 | 10^8 | 10^15 | (al & ~7) == 8 |
| 4 | 10^16 | 10^31 | (al & 0xf0) == 0x10, then checked multiply |

Only the final multiply is checked (`mul` + `seto`): the earlier imul steps
cannot overflow for al <= 19 because 10^15 < 2^64. The ladder therefore
admits exactly al in 1..19 and rejects the rest: al >= 32, or bit 4 clear
without an early exit, misses the ladder bound; al in 20..31 overflows the
final multiply (10^20 > u64::MAX). `cases.tsv` lists all 128 negative byte
values with the verdict. The admitted field range is -2..=18 (per the
admission packet), so through legitimate records only d = -2 and d = -1
reach this ladder; the ladder's own admission (-19..-1) is wider, the same
pattern as the EVM-to-core packet's 39 admitted exponents.

**Divide.** The amount is divided by the ladder result: a 64-bit `div %rcx`
when (amount | pow10) has a bit above bit 31, otherwise a 32-bit `div %ecx`.
The quotient goes to r13. Division by zero is impossible because every
admitted divisor is a non-zero power of ten.

**Exactness.** The remainder is tested: remainder == 0 joins the shared flow
at the success address with dl = 1; remainder != 0 falls to the fallback
address. This is the opposite of the EVM-to-core scaler, which computes and
drops the remainder. The core-to-EVM direction therefore requires an exact
division.

**Fallback (coordinates only, role unresolved).** The fallback path checks
a bound, loads record byte +0x49, computes a float from the amount slot and
two .rodata constants (0x203e80, 0x202ea0) divided by a table entry at
0x584b08 indexed by that byte, stores the float, and propagates tag 0xba
(186). Whether the float is an error detail or a fallback value is
unresolved; the packet claims only the coordinates and the tag.

**Census.** A plain-pattern scan of .text for byte loads with disp32 0xd1
finds exactly six instructions (one genuine REX-prefixed load reports its
tail at 0x3baf4ae in a plain scan; the generator accounts for that tail
explicitly and verifies the true instruction bytes at all six sites):

| Load | FDE | Role |
| --- | --- | --- |
| 0x271568d | 0x2715320 | scaling fragment, copy-1 |
| 0x4d0aa43 | 0x4d0a6d0 | scaling fragment, copy-2 |
| 0x4d0c313 | 0x4d0bfa0 | scaling fragment, copy-3 |
| 0x3baf4ad | 0x3baedf0 | EVM-to-core call site (0x3281770) |
| 0x3baf6ff | 0x3baedf0 | EVM-to-core call site (0x3281770) |
| 0x330668f | 0x33062d0 | struct copy: byte selected by `cmovne` into ebp, no scaling nearby |

**Related work.** The spot-wei-scale-family packet found 22 ladder sites by
the same byte signature and explicitly excluded 7, including these three
handlers and 0x3281770, because they do not load its Location constant.
0x3281770 later received its own packet (EVM-to-core); this packet does the
same for the three evm-decimals sites, bound to a different field (+0xd1)
and a different operation (exact divide for negative exponents). The ladder
shape is shared codegen, not a claim overlap.

## Inferences

- This is the core-to-EVM direction. The signs are reversed against the
  EVM-to-core scaler 0x3281770 (which divides for e >= 0 and multiplies for
  e < 0, dropping remainders); this fragment divides for d < 0 and requires
  exactness. The bytes do not name the direction.
- +0xd1 is `evm_extra_wei_decimals`. The offset, the i8 use and the
  admission packet agree, and the EVM-to-core packet pins the same offset.
- The 20-byte field at +0xbd immediately before the decimals byte is
  consistent with an address field, but that is inference only; the packet
  claims the bytes and the length, not the meaning.
- The fallback float is plausibly an error detail, but its role is
  unresolved and it is not claimed as either an error or a fallback value.

## Implementation and comparison

Rust implementation: not yet implemented. No binary comparison was measured.

## Results and limitations

Metrics are in `evidence.json`.

- Ladder values: 128 of 128 negative byte values modelled, 19 admitted
  (al 1..19), 109 rejected (ladder-bound or pow10-overflow).
- Copies: 3 of 3 share every anchor byte string; the fragment windows are
  all 263 bytes.
- Divide grid: 36 vectors (12 amounts x d in {-1, -2, -19}), 0 mismatches
  against the closed form (quotient, remainder, path, outcome).
- Census: 6 of 6 +0xd1 loads accounted for, 0 unaccounted.
- Tests: 10, including mutated ladder immediates, decimals offsets, divide
  opcodes, flag offsets and digests, each of which makes the generator fail,
  plus one non-anchor control that still generates.

Limits:

- The positive path (d in 0..=18) is not mapped: the byte is kept as r15
  and the fragment enters a bit-loop calling 0x27a1150, whose role is
  unresolved. The multiply for non-negative decimals, and whether it is
  checked, saturating or wrapping, is the open half of this direction.
- The fallback float's role is unresolved (see above).
- The three handlers' callers are unresolved; the handlers are identified
  only by their FDEs and their shared fragment.
- What the success-join does with the quotient beyond the join address is
  out of scope here.
- The divide grid is boundary and seeded values, not all 2^64 amounts. The
  boundary rows rest on the evaluated neighbours plus monotonicity of floor
  division.
- Node #115 is not covered. No progress gate is requested.

Next question: how does the positive path scale for d in 0..=18 — which
helper multiplies the amount by 10^d, and is that multiply checked,
saturating or wrapping?
