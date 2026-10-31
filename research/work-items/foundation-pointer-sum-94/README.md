# foundation-pointer-sum-94: what does the pointer-sum gate compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 29-byte FDE window, its 1 int3 padding byte, the zero naming relocations, the three direct call sites, and the exact pointer-sum rule.
- Excluded: the arguments' meaning, the callers' purpose beyond call-site setup, the next FDE, other pointer-sum helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two zero tests, two leas, two conditional branches, no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x521cc40`, no open pull request title mentions it or pointer-sum, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, field-inequality, bsr-lookup, multiply-mix-div61, global-clamp, two-field-byte-gate, or cursor-walk packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 29-byte body, all instructions, all three callers, and the absence of a naming relocation.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_pointer_sum.py --check research/work-items/foundation-pointer-sum-94/evidence.json
python3 -m unittest tests.test_foundation_pointer_sum -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x521cc40 --stop-address=0x521cc5e artifacts/node/94/hl-node
objdump -d --start-address=0x50ee960 --stop-address=0x50ef0fc artifacts/node/94/hl-node
objdump -d --start-address=0x50f03a0 --stop-address=0x50f0ba0 artifacts/node/94/hl-node
objdump -d --start-address=0x50f18a0 --stop-address=0x50f2bdf artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete linear disassembly from each caller FDE start through its call site (all three sites land on a `call 521cc40` instruction start). The `frames.txt` file retains excerpts selecting the window CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2a4160`, the next FDE at `0x63c9c8`, the three caller FDEs at `0x630430`/`0x63050c`/`0x63056c`, and the next/caller CIE at `0x6205d0`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), locks the next/caller CIE and all five FDE records the same way (the next/caller CIE is "zPLR": P encoding 0x9b, L encoding 0x1b, R encoding 0x1b, i.e. pcrel sdata4 for initial_location), and locks the next FDE record's raw bytes with its GNU-decoded range.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x2a4160` describes `[0x521cc40, 0x521cc5d)`, 29 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the second `ret` at `0x521cc5c` is inside the FDE).
- The stride to the next FDE at `0x521cc5e` is a single int3 byte (`cc`) at `0x521cc5d`. The checker locks body and padding separately; stride is not the FDE extent.
- Precision note, not a scout correction: the 4-byte `nopl` at `0x521cc54` sits **inside** the 29-byte body, between the two return paths (it aligns the sum lea after the first `ret`); it is body bytes, not stride padding. The only stride padding is the single int3 at `0x521cc5d`.

### Instruction walk

- `endbr64` at `0x521cc40`.
- `test %rdi,%rdi` at `0x521cc44`, then `je 0x521cc58` at `0x521cc47` (displacement +0x0f from the next instruction at `0x521cc49`): when rdi is zero, control skips the subtract lea and lands on the sum lea.
- `lea -0xc(%rdi,%rsi,1),%rax` at `0x521cc49`: the both-nonzero result, computed first.
- `test %rsi,%rsi` at `0x521cc4e`, then `je 0x521cc58` at `0x521cc51` (displacement +0x05 from the next instruction at `0x521cc53`): when rsi is zero, control skips the fall-through `ret` and lands on the sum lea, discarding the subtract result.
- `ret` at `0x521cc53`: returns rdi+rsi-0xc when both arguments are nonzero.
- `nopl 0x0(%rax)` at `0x521cc54`: 4 alignment bytes inside the body.
- `lea (%rdi,%rsi,1),%rax` at `0x521cc58`, then `ret` at `0x521cc5c`: returns rdi+rsi when either argument is zero.

### Decoded rule

Return rdi+rsi when rdi == 0 or rsi == 0, else rdi+rsi-0xc, all arithmetic wrapping mod 2^64 (the leas compute mod 2^64 by construction). Both zero tests are full 64-bit tests (`test %rdi,%rdi` / `test %rsi,%rsi`), so there is no low-32-bit subtlety, and both return paths load rax with a lea, so the return value is fully determined — no low-byte-only caveat (unlike packets #27/#32).

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` call sites, each confirmed as an instruction start by linear disassembly from its caller FDE start — explicitly not a complete xref census:

- `0x50ef0f7` (bytes `e8 44 db 12 00`), caller FDE `0x50ee960..0x50efe8d`. Setup immediately before the call: `mov 0x48(%rdi),%rsi` then `mov %r13,%rdi`.
- `0x50f0b9b` (bytes `e8 a0 c0 12 00`), caller FDE `0x50f03a0..0x50f16a2`. Setup immediately before the call: `mov 0x0(%r13),%rax`, `mov %r14,%rdi`, `mov 0x48(%rax),%rsi`.
- `0x50f2bda` (bytes `e8 61 a0 12 00`), caller FDE `0x50f18a0..0x50f3a3a`. Setup immediately before the call: `mov 0x48(%rdi),%rsi` then `mov -0x710(%rbp),%rdi`.

Caller purpose beyond call site and argument setup is not claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). This is a data edge only in the negative sense: the window is reachable only through the three direct calls above, not through a data-pointer table entry.

### Family distance

This window sits in `0x521cxxx`, roughly `0x6c00` above the `0x5215xxx` flag-setter family range. It is a different shape — lea/test/ret with no `orl` constant — and no shared routine or family membership is claimed. The nearest claimed window is the nine-eight gate at `0x5229860` (packet #35), `0xcc20` away. The next FDE at `0x521cc5e` (range 0x38 bytes to `0x521cc96`, frame rbx/rbp/r12-r15) is a different window, not analyzed, and no shared routine is claimed.

## Inferences

- The label "pointer-sum gate" is an inference from the two leas and the two zero tests; the window's source-level name, the arguments' types, and the meaning of the 0xc adjustment are unknown.
- The three callers' argument setup is observed; what the callers do with the returned sum is not claimed.

## Unknowns

- Whether the 0xc adjustment is a header size, a tag width, or something else: unknown, and not needed for the rule.
- Whether indirect or PLT-mediated callers exist: the byte-pattern scan is not a complete xref census, so none are claimed or excluded.
- The provenance of the window (library vs private helper): the absence of a naming relocation does not identify it.

## Limits

- No stdlib type, source-level function, argument meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
