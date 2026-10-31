# foundation-nonzero-below-94: what does the 256-bit nonzero-and-below window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 69-byte FDE window, its 27 alignment-nop padding bytes, the three direct call sites and their caller FDEs, the exact nonzero-and-below rule, and the never-stored edge.
- Excluded: the operands' meaning, the callers' purpose beyond call site and argument setup, the next FDE, other 256-bit helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one four-word OR, one four-word borrow chain, one conditional move, no calls, no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x565dd80`, no open pull request title mentions it or nonzero-below, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, or double-gate packets. The only tree hit for the address is the RE-001 gap inventory line listing the 7-byte gap `0x565dd72–0x565dd80` that *ends* where this window starts; that line is not a claim on the window itself (the same gap-end precedent as packet #28).

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_nonzero_below.py --check research/work-items/foundation-nonzero-below-94/evidence.json
python3 -m unittest tests.test_foundation_nonzero_below -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x565dd80 --stop-address=0x565dde0 artifacts/node/94/hl-node
objdump -d --start-address=0x56507c0 --stop-address=0x5650951 artifacts/node/94/hl-node
objdump -d --start-address=0x5650ba0 --stop-address=0x5650d31 artifacts/node/94/hl-node
objdump -d --start-address=0x5651e50 --stop-address=0x5651eb8 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete linear disassembly of the three caller FDEs, which is how each call site was confirmed as an instruction start (the instruction immediately before each site ends exactly at the site). The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2dc334`, and the next FDE at `0x2dc348`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2dc334` describes `[0x565dd80, 0x565ddc5)`, 69 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `repz ret` at `0x565ddc3` is inside the FDE).
- The unwind index stride to the next entry is 96 bytes, ending at `0x565dde0`, only because 27 alignment bytes pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those 27 padding bytes, and the checker locks the 69-byte body and the padding separately. The next FDE starts exactly at `0x565dde0` (range 142 bytes to `0x565de6e`).
- The padding is `nop`/`nopw`/`nopl` alignment bytes (`90`, `66 66 2e 0f 1f 84 00 …`, `0f 1f 40 00`), **not** `int3`. The checker locks the exact 27 padding bytes and additionally asserts no `0xcc` appears in them, so a future description of this stride as int3 padding would fail the check.

### Instruction sequence

Offsets are relative to the FDE start `0x565dd80`:

| Offset | Bytes | Instruction |
| ------ | ----- | ----------- |
| 0x00 | `f3 0f 1e fa` | `endbr64` |
| 0x04 | `48 8b 07` | `mov (%rdi),%rax` — minuend word 0 |
| 0x07 | `4c 8b 4f 08` | `mov 0x8(%rdi),%r9` — minuend word 1 |
| 0x0b | `4c 8b 57 10` | `mov 0x10(%rdi),%r10` — minuend word 2 |
| 0x0f | `4c 8b 5f 18` | `mov 0x18(%rdi),%r11` — minuend word 3 |
| 0x13 | `49 89 c0` | `mov %rax,%r8` — word 0 moves to the subtract accumulator |
| 0x16 | `4c 09 c8` | `or %r9,%rax` — OR chain, word 1 |
| 0x19 | `4c 09 d0` | `or %r10,%rax` — OR chain, word 2 |
| 0x1c | `4c 09 d8` | `or %r11,%rax` — OR chain, word 3; rax is now the OR of all four minuend words |
| 0x1f | `4c 2b 06` | `sub (%rsi),%r8` — subtract subtrahend word 0 |
| 0x22 | `4c 1b 4e 08` | `sbb 0x8(%rsi),%r9` — subtract word 1 with borrow |
| 0x26 | `4c 1b 56 10` | `sbb 0x10(%rsi),%r10` — subtract word 2 with borrow |
| 0x2a | `4c 1b 5e 18` | `sbb 0x18(%rsi),%r11` — subtract word 3 with borrow |
| 0x2e | `48 19 f6` | `sbb %rsi,%rsi` — rsi becomes 0 (no borrow) or -1 (borrow-out) |
| 0x31 | `48 c7 c2 01 00 00 00` | `mov $0x1,%rdx` |
| 0x38 | `48 83 f8 00` | `cmp $0x0,%rax` — zero test on the OR |
| 0x3c | `48 0f 45 c2` | `cmovne %rdx,%rax` — rax is 1 iff the minuend is nonzero, else 0 |
| 0x40 | `48 21 f0` | `and %rsi,%rax` — 1 iff nonzero AND borrow-out |
| 0x43 | `f3 c3` | `repz ret` |

### The predicate, derived step by step

- The OR chain leaves `rax = word0 | word1 | word2 | word3` of the minuend, so the `cmp`/`cmovne` pair yields 1 exactly when the minuend is nonzero.
- The `sub`/`sbb` chain computes `minuend - subtrahend` word by word, low to high, propagating borrows. The final `sbb %rsi,%rsi` computes `rsi - rsi - CF = -CF`, so `rsi` is -1 exactly when the subtraction borrowed out of the top word, i.e. exactly when `minuend < subtrahend` as unsigned 256-bit values, and 0 otherwise.
- The final `and` therefore yields 1 exactly when **0 < minuend < subtrahend**, else 0. The window returns that value in `rax` (fully determined: `cmovne` writes the whole register from the constant 1 or leaves the OR result 0, and the `and` with 0/-1 preserves a 0/1 value).

### The never-stored edge

- The four-word difference is computed into caller-saved registers `r8`–`r11` and is **never stored to memory**: no store instruction appears in the locked sequence, and the only memory operations are the eight loads (four from each operand). This window returns only the predicate, not the difference. Any description of it as a subtract routine that writes its result would be wrong.

### Incoming calls

- The exact `.text` byte-pattern scan covering 70,370,352 bytes finds exactly three direct `e8` call sites: `0x56508a6` (caller FDE `0x56507c0..0x5650951`), `0x5650c86` (caller FDE `0x5650ba0..0x5650d31`), and `0x5651e5f` (caller FDE `0x5651e50..0x5651eb8`). Each was confirmed as an instruction start by linear disassembly from its caller FDE start: the instruction immediately before each site ends exactly at the site, and the call bytes at each site decode to target `0x565dd80`. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Data edge

- No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). The window has no RIP-relative operand, table, or constant pool of its own.

### No scout correction needed

- Every scouted element verified exactly: FDE range, padding count and nop kind, all nineteen instructions, the three callers and their FDEs, and the absence of a naming relocation.

## Inferences

- The "nonzero-and-below predicate" label is an inference from the observed instruction shape (four-word OR, four-word borrow chain, cmovne, AND with the borrow mask). It is kept separate from the observed rule above.
- Nothing else is inferred: no source-level function, no operand meaning, no caller purpose, and no component ownership are claimed.

## Unknowns

- What the two 256-bit operands represent, why the predicate combines nonzero with below (rather than either alone), and whether any caller reaches this window through a register-indirect or data path the byte-pattern scan cannot see.
- The next FDE at `0x565dde0` (142 bytes) is a different window and is not analyzed here.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of other direct callers does not prove the window is reachable only from the three sites.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
