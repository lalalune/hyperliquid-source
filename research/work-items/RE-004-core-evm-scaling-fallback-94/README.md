# RE-004: the shared core-to-EVM scaling fallback in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made;
  the reference submodule was empty in this worktree
- Claim status: observation for the instructions, constants, table, entry
  set, record layout and evaluated behaviour; inference for the
  direction, the field meanings and the virtual call; unresolved items
  are listed under Results and limitations
- Scope included: the three handlers' shared fallback entry set, bound
  check and panic block, record-byte load, SSE float sequence, pow10
  table, record-construction tail, flag-error entry, remainder test, and
  the success join's separation from the fallback return
- Scope excluded: the negative-decimals divide mechanism (#157 packet)
  and the non-negative square-and-multiply loop (#158 packet), the
  remainder of the three 6 KB handlers, the virtual callee at
  [object + 0x20], the consumer of the output record, the post-success
  flow, the 93 further readers of the pow10 table (unmapped), and
  node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/core_evm_scaling_fallback94.py --out research/work-items/RE-004-core-evm-scaling-fallback-94
python3 -m unittest discover -s tests -p 'test_core_evm_scaling_fallback94.py'
(cd research/work-items/RE-004-core-evm-scaling-fallback-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x271627d --stop-address=0x27163e8 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4d0b680 --stop-address=0x4d0b7e8 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4d0cf50 --stop-address=0x4d0d0b8 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes a few seconds.
Outputs: `evidence.json`, `sites.tsv`, `fallback_cases.tsv` and `windows.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. The fallback belongs to the same
three handlers the #157 (negative) and #158 (non-negative) packets map;
it is the path every scaling failure in those packets converges on. The
#157 packet recorded the fallback address only; the #158 packet recorded
the success flag after it. Neither packet mapped the fallback body.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the remainder, float, fallback
and flag windows are transcribed byte-for-byte in `windows.txt` and
hashed in `evidence.json`. FDE bounds are unwind-described ranges, not
validated function boundaries.

| Copy | FDE | Fallback | Panic | Amount slot | Result slot | Tail entry | Ret | Success join |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| copy-1 | 0x2715320..0x2716bc0 | 0x271628d | 0x2716954 | [rsp+0x58] | [rsp+0x40] | 0x27162e4 | 0x27163e7 | 0x27163e8 |
| copy-2 | 0x4d0a6d0..0x4d0bfa0 | 0x4d0b690 | 0x4d0bd36 | [rsp+0x48] | [rsp+0x30] | 0x4d0b6e7 | 0x4d0b7e7 | 0x4d0b7e8 |
| copy-3 | 0x4d0bfa0..0x4d0d870 | 0x4d0cf60 | 0x4d0d606 | [rsp+0x48] | [rsp+0x30] | 0x4d0cfb7 | 0x4d0d0b7 | 0x4d0d0b8 |

**Entry set.** Six ways in, per copy — five jumps plus the remainder
fall-through. The remainder test is shared by the 32-bit and 64-bit
divide paths and sits immediately before the fallback entry, so a
nonzero remainder falls through into the fallback.

| Entry | copy-1 | copy-2 | copy-3 |
| --- | --- | --- | --- |
| ladder failure (bit 0x10 clear) | 0x27156f4 je | 0x4d0aaaa je | 0x4d0c37a je |
| ladder failure (masked value != 0x10) | 0x2715713 jne | 0x4d0aac9 jne | 0x4d0c399 jne |
| ladder failure (checked multiply overflow) | 0x271571e jne | 0x4d0aad4 jne | 0x4d0c3a4 jne |
| positive loop overflow | 0x2715955 jmp | 0x4d0ad34 jmp | 0x4d0c604 jmp |
| positive final multiply overflow | 0x27159f2 jne | 0x4d0ae0f jne | 0x4d0c6df jne |
| negative remainder != 0 (fall-through) | 0x2716284 test | 0x4d0b687 test | 0x4d0cf57 test |

**Bound check and panic block.** At the fallback entry the handler
compares the record index against the count (copy-1: `cmp r15,
[rsp+0x218]` frame slots via rbp; copies 2/3: `cmp rbp, [r15+0x218]`)
and jumps to a shared panic-shaped block on `jae`: `lea rdi,
[0x56f21f0]; call [GOT 0x576e470]; jmp join` (join: copy-1 0x2716b0c,
copy-2 0x4d0beeb, copy-3 0x4d0d7bb). The callee is not identified; the
block is reported as panic-shaped only. On success the handler loads
the record byte: array base from the frame ([rbp+0x210] copy-1,
[r15+0x210] copies 2/3), index times stride 0xe8, byte at record + 0x49.

**Float sequence.** Identical in all three copies up to register
allocation and stack slots:

| Step | copy-1 | Meaning |
| --- | --- | --- |
| `movsd xmm0, [amount_slot]` | 0x27162a8 | the u64 core amount |
| `unpcklps xmm0, [0x203e80]` | 0x27162ae | f32 lanes [0x43300000, 0x45300000, 0, 0] |
| `subpd xmm0, [0x202ea0]` | 0x27162b5 | doubles [2^52, 2^84] |
| `movzx eax, byte [record + 0x49]` | 0x27162bd | table index |
| `movapd xmm1, xmm0` | 0x27162c2 | copy |
| `unpckhpd xmm1, xmm0` | 0x27162c6 | xmm1 = (high, high) |
| `addsd xmm1, xmm0` | 0x27162ca | horizontal add |
| `lea rcx, [0x584b08]` | 0x27162ce | pow10 table base |
| `divsd xmm1, [rcx + rax*8]` | 0x27162d5 | divide by table[byte] |
| `movapd [result_slot], xmm1` | 0x27162da | store |

Traced lane by lane: after `movsd` the low double holds the amount's
bits and the high double is 0. `unpcklps` makes the low double
2^52 + (amount mod 2^32) and leaves the high double 0. `subpd` makes
them (amount mod 2^32) and -2^84. The horizontal add sums those two
lanes. The stored double is therefore:

```
fallback_double = (f64(amount mod 2^32) - 2^84) / pow10_table[byte]
```

This is NOT `f64(amount) / 10^byte`: the high 32 bits of the amount are
dropped by the lane shuffle, and the -2^84 term dominates every result.
Across the 56-case grid in `fallback_cases.tsv` (8 amounts x 7 bytes)
the fallback value equals the naive scaled amount in 0 cases.

| amount | byte | lo32 | table[byte] | fallback_double | naive_double |
| --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 1.0 | -1.9342813113834067e+25 | 0.0 |
| 2^32 | 18 | 0 | 1e+18 | -19342813.11383407 | 4.294967296e-09 |
| 2^64 - 1 | 0 | 2^32 - 1 | 1.0 | -1.9342813113834063e+25 | 1.8446744073709552e+19 |
| 2^64 - 1 | 255 | 2^32 - 1 | 1e+255 | -1.9342813113834062e-230 | 1.8446744073709552e-236 |

**Pow10 table.** At 0x584b08, 256 doubles. The table is exactly the
successive IEEE multiply-by-10 chain from 1.0 (table[0] = 1.0,
table[i+1] = table[i] * 10.0, verified for all 256 entries). It is not
the correctly-rounded power: it differs from `float(10**b)` at 195 of
the 256 entries (the full list is in `evidence.json`). The case table
uses the actual table value as the divisor throughout. The table is
shared, not fallback-specific: a full-.text disassembly sweep
(objdump `-d` over 0x1343c80..0x56608b0) finds 96 LEA instructions
whose RIP-relative target is the table base, including the three
fallback LEAs; the other 93 readers are not mapped.

**Record tail.** Shared by the float path (tag 0xba, set at the tail
entry) and the flag-error path (tag 0x14a, set at the flag-error block,
which jumps straight to the tail entry and skips the float computation
and the bound check). The tail null-checks the object from the frame
and, if non-null, calls the virtual slot at [object + 0x20] with
(out_ptr, index, count); the callee is not identified. It then copies
the input fields into the output record at [r12]:

| Record offset | Content |
| --- | --- |
| +0x0 | tag word (bx: 0xba float path, 0x14a flag-error path) |
| +0x2 | dword from the frame |
| +0x6 | word from the frame |
| +0x8 | double from [result_slot] (computed float, or the prologue slot value on the 0x14a path) |
| +0x10 | 16 bytes from the frame |
| +0x28 / +0x38 / +0x48 | 16 bytes each from the frame |
| +0x58 | qword from the frame |

The epilogue (`add rsp, 0x618`; pops; `ret`) returns directly. On the
0x14a path the [result_slot] is never written by this path, so the
record's +0x8 double carries whatever the prologue stored there (for
copy-1, the rcx argument saved at 0x2715476). The success join sits
immediately after the ret and is a different path: it zeroes a 16-byte
slot (copy-1 [rsp+0x1f8], copies 2/3 [rsp+0x218]) and continues on the
shared flow; it does not return through the fallback's ret, and the
fallback does not jump to it.

**Flag-error path.** The fragment requires the record flag byte at
+0xbc to equal 1 (`cmp byte [base + index*0xe8 + 0xbc], 0x1`); otherwise
it sets bx = 0x14a and jumps to the tail entry. Flag-test addresses:
copy-1 0x2715641 / jne 0x271564a -> 0x2715746; copy-2 0x4d0a9f7 /
jne 0x4d0aa00 -> 0x4d0aafc; copy-3 0x4d0c2c7 / jne 0x4d0c2d0 ->
0x4d0c3cc.

## Inferences

- This is the core-to-EVM direction, the same direction and the same
  handlers as the #157 and #158 packets. The bytes do not name the
  direction.
- The record byte at +0x49 is the fallback's table index. It is a
  different offset from the +0xd1 decimals byte the #157/#158 packets
  map, and its field meaning is unresolved; it is not claimed to be
  the decimals value.
- The virtual call at [object + 0x20] plausibly notifies or records
  something about the failed scaling, but its callee and effect are
  unresolved and are not claimed.
- The panic block's callee is unresolved; it is reported as
  panic-shaped only.
- Why the float sequence computes `(lo32 - 2^84) / table[byte]` --
  miscompiled u64-to-double conversion, deliberate sentinel, or
  something else -- is unresolved and is not claimed. The packet
  reports the observed formula exactly.

## Implementation and comparison

Rust implementation: not yet implemented. No binary comparison was measured.

## Results and limitations

Metrics are in `evidence.json`.

- Copies: 3 of 3 share every anchor byte string up to register
  allocation and stack slots; all 5 entry jumps plus the remainder
  test verified per copy with their branch targets.
- Table: 256 of 256 entries match the successive-x10 chain exactly;
  195 of 256 differ from the correctly-rounded power.
- Case grid: 56 vectors (8 amounts x 7 bytes), 0 equal to the naive
  scaled amount, 0 mismatches against the traced SSE formula.
- Tests: 28, including mutated bound compares, float opcodes, table
  immediates, tags, virtual-call bytes, record stores, remainder tests,
  entry jumps and panic blocks, each of which makes the generator
  fail, plus one non-anchor control that still generates identically.

Limits:

- The three handlers' callers are unresolved; the handlers are
  identified only by their FDEs and their shared fragments.
- The virtual callee, the panic callee, and the consumer of the
  tag-0xba / tag-0x14a records are not mapped; what the downstream
  flow does with the negative fallback double is unknown.
- The +0x49 record byte's field meaning is unresolved.
- The float formula's intent is unresolved (see Inferences).
- The 93 further LEA readers of the pow10 table are not mapped; the
  table is shared across the binary, so the fallback's divisor table
  is not evidence of a fallback-specific constant.
- The case grid is boundary and seeded values, not all 2^64 amounts
  or all 256 bytes; the formula itself is byte-exact, so the grid
  checks the evaluator, not the formula's range.
- Node #115 is not covered. No progress gate is requested.

Next question: what is the +0x49 record byte, and what consumes
tag-0xba records — does the downstream flow treat the negative
fallback double as an error marker, or does it use it as a value?
