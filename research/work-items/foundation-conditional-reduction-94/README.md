# foundation-conditional-reduction-94: what does the 192-bit conditional-reduction window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 91-byte FDE window, its 5-byte nop/nopl stride padding, the zero naming relocations, the four direct call sites, and the exact conditional-reduction rule.
- Excluded: the inputs' meaning, the add-back operand's role, any caller behavior, the next FDE, other arithmetic helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two multiplies build a 192-bit product, a sub/sbb chain subtracts it from a 192-bit buffer, a borrow mask conditionally adds the 128-bit input back to the low two words, and the top word is overwritten with the scalar adjusted by the borrow — no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x565ee40`, no open pull request title mentions it or conditional-reduction, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, or dual-zero packets.

This window is bound **alone**. No census of similar windows is claimed.

## Scout correction (read first)

The round-7 scout note described this window as "out(192-bit) -= scalar * in(128-bit)". That summary is **imprecise for the top word** and is not repeated as the rule below. The retained bytes show the top-word difference (`out[2] - p2 - borrow`, computed in rax at body offset 0x32) is **never stored**: the only store to `out + 0x10` is rcx, the scalar adjusted by the borrow mask. The low two words do follow subtract-then-conditionally-add-back, but the top word does not follow the subtraction at all — it is unconditionally overwritten. The checker locks the verified bytes, not the scout summary. Every other scouted element verified exactly: the FDE range, the 91-byte body, the four scan hits, and the gap artifact (see below).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_conditional_reduction.py --check research/work-items/foundation-conditional-reduction-94/evidence.json
python3 -m unittest tests.test_foundation_conditional_reduction -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x565ee40 --stop-address=0x565eea0 artifacts/node/94/hl-node
objdump -d --start-address=0x564a900 --stop-address=0x564ab48 artifacts/node/94/hl-node
objdump -d --start-address=0x56503e0 --stop-address=0x5650617 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. The `caller.objdump.txt` file retains complete disassembly of both caller FDEs. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2dc468`, and the next FDE at `0x2dc47c`. The checker locks the window FDE records and their CIE raw bytes, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value).
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2dc468` describes `[0x565ee40, 0x565ee9b)`, 91 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `repz ret` at `0x565ee99` is inside the FDE).
- Padding is **5 bytes** of alignment nops, not int3: `90` at `0x565ee9b` and `0f 1f 40 00` (`nopl 0x0(%rax)`) at `0x565ee9c`, to the 96-byte unwind-index stride ending at `0x565eea0`. Stride is not the FDE extent; the checker locks the body and the padding separately. The next FDE starts exactly at `0x565eea0` (range 26 bytes to `0x565eeba`) and is a different window, not analyzed here.
- The RE-001 gap inventory lists a gap `0x565dd72–0x565dd80` ending where packet #34's window starts, and a gap `0x565ee3d–0x565ee40` ending where this window starts. The latter is a gap-END artifact only, not a claim about this window — the same precedent as packet #28.

### Instruction sequence

Offsets are relative to the FDE start `0x565ee40`. Arguments under the System V ABI: `rdi` = out pointer (3 words), `rsi` = in pointer (2 words), `rdx` = scalar. All words are unsigned 64-bit.

| Offset | Bytes | Instruction |
| ------ | ----- | ----------- |
| 0x00 | `f3 0f 1e fa` | `endbr64` |
| 0x04 | `48 89 d0` | `mov %rdx,%rax` — scalar copy |
| 0x07 | `48 89 d1` | `mov %rdx,%rcx` — scalar copy |
| 0x0a | `48 f7 26` | `mulq (%rsi)` — rdx:rax = scalar * in[0] |
| 0x0d | `49 89 c0` | `mov %rax,%r8` — r8 = product word 0 |
| 0x10 | `48 89 c8` | `mov %rcx,%rax` — scalar reload |
| 0x13 | `49 89 d1` | `mov %rdx,%r9` — r9 = hi(scalar * in[0]) |
| 0x16 | `48 f7 66 08` | `mulq 0x8(%rsi)` — rdx:rax = scalar * in[1] |
| 0x1a | `49 01 c1` | `add %rax,%r9` — r9 = product word 1 (low part) |
| 0x1d | `48 83 d2 00` | `adc $0x0,%rdx` — rdx = product word 2 (carry in) |
| 0x21 | `4c 8b 17` | `mov (%rdi),%r10` — out[0] |
| 0x24 | `4c 8b 5f 08` | `mov 0x8(%rdi),%r11` — out[1] |
| 0x28 | `48 8b 47 10` | `mov 0x10(%rdi),%rax` — out[2] |
| 0x2c | `4d 29 c2` | `sub %r8,%r10` — out[0] -= product word 0 |
| 0x2f | `4d 19 cb` | `sbb %r9,%r11` — out[1] -= product word 1 + borrow |
| 0x32 | `48 19 d0` | `sbb %rdx,%rax` — out[2] -= product word 2 + borrow (computed, then discarded) |
| 0x35 | `4d 19 c0` | `sbb %r8,%r8` — r8 = 0 - borrow = borrow mask (0 or all-ones) |
| 0x38 | `4c 01 c1` | `add %r8,%rcx` — rcx = scalar + mask = scalar or scalar - 1 |
| 0x3b | `4d 89 c1` | `mov %r8,%r9` — mask copy |
| 0x3e | `4c 23 06` | `and (%rsi),%r8` — r8 = mask & in[0] |
| 0x41 | `4c 23 4e 08` | `and 0x8(%rsi),%r9` — r9 = mask & in[1] |
| 0x45 | `4d 01 c2` | `add %r8,%r10` — out[0] += mask & in[0] |
| 0x48 | `4d 11 cb` | `adc %r9,%r11` — out[1] += mask & in[1] + carry |
| 0x4b | `4c 89 17` | `mov %r10,(%rdi)` — store out[0] |
| 0x4e | `4c 89 5f 08` | `mov %r11,0x8(%rdi)` — store out[1] |
| 0x52 | `48 89 4f 10` | `mov %rcx,0x10(%rdi)` — store out[2] = scalar or scalar - 1 |
| 0x56 | `48 89 c8` | `mov %rcx,%rax` — return = stored top word |
| 0x59 | `f3 c3` | `repz ret` |

### The decoded rule

Let `P = scalar * (in[0] + in[1] * 2^64)` as a 192-bit value with words
`p0 = lo(scalar * in[0])`, `p1 = hi(scalar * in[0]) + lo(scalar * in[1])`
(with carry into p2), `p2 = hi(scalar * in[1]) + carry`. Let `borrow` be 1
iff the 192-bit out value is strictly below `P`, else 0. Then the window stores:

- `out[0] = (out[0] - p0 + (borrow ? in[0] : 0)) mod 2^64`, with carry into the next word;
- `out[1] = (out[1] - p1 - borrow0 + (borrow ? in[1] : 0) + carry) mod 2^64`;
- `out[2] = scalar - borrow` (scalar when no borrow, scalar - 1 when borrow);
- return value = `out[2]` as stored.

Sharp edges, all locked by the checker:

- The top-word subtraction result at offset 0x32 is computed in rax and then
  **discarded**: rax is overwritten at offset 0x56 and never stored. The only
  store to `out + 0x10` is the scalar adjusted by the borrow mask. The entry
  top word still participates in the borrow decision (the 192-bit comparison
  includes it); only its subtraction result is discarded.
- Carry out of the 128-bit add-back (low two words) is likewise discarded:
  it cannot propagate into `out[2]`, because `out[2]` is overwritten.
- The return value equals the stored top word, not a pointer and not the
  subtraction result. The "modulus" wording names only the observed add-back
  operand (the 128-bit input); no modular-arithmetic role is claimed.

Worked edges (restatements of the bytes, checked by the tool):

- No borrow: out = (100, 200, 300), in = (3, 0), scalar = 7 → (79, 200, 7), return 7.
- Borrow, scalar 1: out = (3, 4, 0), in = (5, 9), scalar = 1 → (3, 4, 0), return 0 (product equals the input, so subtract-then-add-back restores the entry lows).
- Borrow, scalar 2: out = (3, 4, 0), in = (5, 9), scalar = 2 → (2^64 - 2, 2^64 - 6, 1), return 1.
- Borrow, out zero: out = (0, 0, 0), in = (5, 9), scalar = 1 → (0, 0, 0), return 0.
- Top-word discard: in = 0, scalar = 5, entry top word 7 vs 9 → stored top word 5 in both cases.
- Scalar zero: product zero, no borrow, stored triple is the entry lows with top word 0.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly four direct `e8` call sites, each confirmed as an instruction start by linear disassembly from its caller FDE start — explicitly not a complete xref census:

- `0x564a9ae` and `0x564a9e3`, both in caller FDE `0x564a900..0x564ab48`;
- `0x5650496` and `0x56504d5`, both in caller FDE `0x56503e0..0x5650617`.

Caller purpose beyond call site and argument setup is not claimed. The window may still be reached through a data-pointer path or a register-indirect call the scan cannot see; neither is claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The "192-bit conditional reduction" label is an inference from the observed instruction shape (two multiplies, sub/sbb chain, borrow-mask add-back, scalar top-word store). It is kept separate from the observed rule above.
- Nothing else is inferred: no source-level function, no input meaning, no add-back operand role, no caller purpose, and no component ownership are claimed.

## Unknowns

- What the three-word buffer, the two-word input, and the scalar represent, and why the top word carries the adjusted scalar rather than the subtraction result.
- Whether any caller reaches this window through a register-indirect or data path the byte-pattern scan cannot see.
- The next FDE at `0x565eea0` (26 bytes) is a different window and is not analyzed here.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not prove the window is unreachable by other paths.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
